# Flask Ticket Application

This project is a simple Flask web application that allows users to submit error reports through a ticket submission form. The application captures user input, validates required fields, and provides feedback upon submission.

## Project Structure

```
flask-ticket-app
├── app.py                # Main application file
├── requirements.txt      # Project dependencies
├── templates             # Directory for HTML templates
│   └── ticket.html       # Ticket submission form template
├── static                # Directory for static files (CSS, images, etc.)
│   └── style.css         # CSS styles for the application
└── README.md             # Project documentation
```

## Requirements

To run this application, you need to have Python installed on your machine. You also need to install the required packages listed in `requirements.txt`.

## Installation

1. Clone the repository or download the project files.
2. Navigate to the project directory:
   ```
   cd flask-ticket-app
   ```
3. Create a virtual environment (optional but recommended):
   ```
   python -m venv venv
   ```
4. Activate the virtual environment:
   - On Windows:
     ```
     venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```
     source venv/bin/activate
     ```
5. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Running the Application

To run the Flask application, execute the following command in your terminal:
```
python app.py
```

The application will start, and you can access it in your web browser at `http://127.0.0.1:5000/`.

## Usage

- Fill out the ticket submission form with the required information.
- Click the "Submit Report" button to send your ticket.
- You will receive feedback on the submission status.

## License

This project is open-source and available under the MIT License.