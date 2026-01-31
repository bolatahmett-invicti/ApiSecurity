# Build once
docker build -t api-scanner .

# Scan codebase
docker run --rm -v $(pwd):/code:ro -v $(pwd)/output:/output api-scanner

# With Invicti upload
docker run --rm \
  -v $(pwd):/code:ro \
  -v $(pwd)/output:/output \
  -e INVICTI_SYNC=true \
  -e INVICTI_URL=https://your.invicti.com \
  -e INVICTI_USER=xxx \
  -e INVICTI_TOKEN=xxx \
  -e INVICTI_WEBSITE_ID=xxx \
  api-scanner