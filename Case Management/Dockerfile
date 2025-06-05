# Use official Python image
FROM python:3.9

# Set the working directory
WORKDIR /app

# Copy project files into the container
COPY . .

# Install required dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV FLASK_APP=dashboard.py
ENV FLASK_ENV=production

# Expose Flask's default port
EXPOSE 8000

# Run the Flask app using Gunicorn for production
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "dashboard:app"]