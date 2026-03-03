#!/bin/bash

# Deploy MCP Toolbox to remote server
# Usage: ./deploy.sh [mode] [server-ip]
# Modes:
#   full     - Build image + copy config + deploy (default)
#   config   - Copy config files only + restart service
#   restart  - Restart service only (no copy, no build)
#   logs     - Show recent container logs
#   status   - Show container status
#
# Examples:
#   ./deploy.sh                    # full deploy to 172.16.1.86
#   ./deploy.sh full 172.16.1.86   # full deploy
#   ./deploy.sh config             # config-only update + restart
#   ./deploy.sh restart            # just restart the service
#   ./deploy.sh logs               # tail logs
#   ./deploy.sh status             # check container status

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parse arguments: if first arg looks like an IP, treat as full deploy
MODE="full"
SERVER_IP="172.16.1.86"
if [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SERVER_IP="$1"
elif [ -n "$1" ]; then
    MODE="$1"
    if [ -n "$2" ]; then
        SERVER_IP="$2"
    fi
fi

REMOTE_USER=${REMOTE_USER:-"ashankar"}
DEPLOY_PATH=${DEPLOY_PATH:-"~/mcp-toolbox"}
SSH_KEY=${SSH_KEY:-"~/.ssh/id_ed25519_genai"}
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10"

IMAGE_NAME="mcp-toolbox"
SERVICE_NAME="mcp-toolbox"

# Get the directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}MCP Toolbox Deployment${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Mode:          ${GREEN}${MODE}${NC}"
echo -e "Target Server: ${GREEN}${SERVER_IP}${NC}"
echo -e "Remote User:   ${GREEN}${REMOTE_USER}${NC}"
echo -e "Deploy Path:   ${GREEN}${DEPLOY_PATH}${NC}"
echo ""

# --- Helper functions ---

copy_config() {
    echo -e "${YELLOW}Copying config files to remote...${NC}"
    ssh ${SSH_OPTS} ${REMOTE_USER}@${SERVER_IP} "mkdir -p ${DEPLOY_PATH}"
    scp ${SSH_OPTS} "${SCRIPT_DIR}/tools.yaml" "${REMOTE_USER}@${SERVER_IP}:${DEPLOY_PATH}/tools.yaml"
    scp ${SSH_OPTS} "${SCRIPT_DIR}/docker-compose.remote.yml" "${REMOTE_USER}@${SERVER_IP}:${DEPLOY_PATH}/docker-compose.yml"
    echo -e "${GREEN}Config files copied.${NC}"
}

build_image() {
    echo -e "${YELLOW}Building ${IMAGE_NAME} for AMD64...${NC}"
    docker buildx build --platform linux/amd64 --no-cache \
        -t ${IMAGE_NAME}:latest \
        --load \
        -f "${SCRIPT_DIR}/Dockerfile.deploy" \
        "${PROJECT_DIR}"
}

transfer_image() {
    echo -e "${YELLOW}Saving and compressing Docker image...${NC}"
    docker save ${IMAGE_NAME}:latest | gzip > /tmp/${IMAGE_NAME}.tar.gz
    echo -e "${GREEN}Image saved: $(du -h /tmp/${IMAGE_NAME}.tar.gz | cut -f1)${NC}"

    echo -e "${YELLOW}Transferring image to remote server...${NC}"
    scp ${SSH_OPTS} /tmp/${IMAGE_NAME}.tar.gz ${REMOTE_USER}@${SERVER_IP}:${DEPLOY_PATH}/
    rm -f /tmp/${IMAGE_NAME}.tar.gz
}

load_and_restart() {
    local LOAD_IMAGE=${1:-false}
    echo -e "${YELLOW}Deploying on remote server...${NC}"
    ssh ${SSH_OPTS} ${REMOTE_USER}@${SERVER_IP} bash -s << DEPLOY_EOF
        cd ${DEPLOY_PATH}

        if [ "${LOAD_IMAGE}" = "true" ]; then
            echo "Loading Docker image..."
            gunzip -f ${IMAGE_NAME}.tar.gz
            docker load -i ${IMAGE_NAME}.tar
            rm -f ${IMAGE_NAME}.tar
        fi

        echo "Recreating ${SERVICE_NAME}..."
        docker compose up -d --force-recreate ${SERVICE_NAME}

        echo "Checking service status..."
        docker compose ps ${SERVICE_NAME}

        echo "Waiting 3s for startup..."
        sleep 3
        echo "Health check:"
        curl -s http://localhost:5000 || echo "Server not yet ready (may still be starting)"
DEPLOY_EOF
}

show_logs() {
    ssh ${SSH_OPTS} ${REMOTE_USER}@${SERVER_IP} "docker logs ${SERVICE_NAME} 2>&1 | tail -30"
}

show_status() {
    ssh ${SSH_OPTS} ${REMOTE_USER}@${SERVER_IP} "cd ${DEPLOY_PATH} && docker compose ps ${SERVICE_NAME} && echo '---' && docker logs ${SERVICE_NAME} 2>&1 | tail -5"
}

# --- Execute based on mode ---

case ${MODE} in
    full)
        copy_config
        build_image
        transfer_image
        load_and_restart true
        ;;
    config)
        copy_config
        load_and_restart false
        ;;
    restart)
        load_and_restart false
        ;;
    logs)
        show_logs
        exit 0
        ;;
    status)
        show_status
        exit 0
        ;;
    *)
        echo -e "${RED}Unknown mode: ${MODE}${NC}"
        echo "Usage: ./deploy.sh [full|config|restart|logs|status] [server-ip]"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ MCP Toolbox Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "MCP Toolbox is running on ${GREEN}http://${SERVER_IP}:5000${NC}"
echo ""
echo -e "Test with:"
echo -e "  curl http://${SERVER_IP}:5000"
echo ""
echo -e "Invoke a tool with dynamic credentials:"
echo -e '  curl -X POST http://'"${SERVER_IP}"':5000/api/tool/run_sql/invoke \\'
echo -e '    -H "Content-Type: application/json" \\'
echo -e '    -d '"'"'{"sql": "SELECT 1", "db_credentials": {"host": "172.16.1.87", "port": "5432", "user": "myuser", "password": "mypass", "database": "mydb"}}'"'"
echo ""
