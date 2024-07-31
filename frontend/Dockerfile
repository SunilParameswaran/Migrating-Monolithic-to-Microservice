# Use the official Python image as base
FROM python:3.11.4

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code into the container


# Expose the port the service runs on
EXPOSE 8000

# Command to run the service
CMD ["python", "frontend_service.py"]
