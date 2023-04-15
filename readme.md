# Build Docker container
docker build -t tamilchain .

# Run Docker container
docker run -p 5000:5000 tamilchain