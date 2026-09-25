#!/bin/bash
set -euo pipefail
echo "Deploying..."
rsync -avz ./build/ user@server:/var/www/
systemctl restart nginx
echo "Done!"
