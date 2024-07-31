# Use the official Python image as base
FROM python:3.11.4

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code into the container
COPY order_service.py .

# Expose the port the service runs on
EXPOSE 5004

# Command to run the service
CMD ["python", "order_service.py"]
