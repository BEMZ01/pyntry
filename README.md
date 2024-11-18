# Pyntry

Pyntry is a Python-based web application that interacts with the Open Food Facts API to pull product data based on barcodes. This project uses SQLite for database management and is configured to run on localhost.

It was made to clean up my kitchen and help me keep track of the products I have at home.
## Getting Started
### Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/BEMZ01/Pyntry.git
    cd Pyntry
    ```

2. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Set up environment variables**:
    - Copy the `.env.example` file to `.env`:
        ```bash
        cp .env.example .env
        ```
    - Update the `.env` file with your configuration.

### Usage

1. **Run the application**:
    ```bash
    python main.py
    ```

2. **Access the application**:
    Open your web browser and go to `http://127.0.0.1:8000`.

## Contributing

We welcome contributions from everyone. Please read the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute to this project.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Contact

If you have any questions, feel free to reach out to me on GitHub or via email.

Happy coding!