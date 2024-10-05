import bcrypt
import csv
import re
import requests

# Constants
CSV_FILE = "regno.csv"
LOGIN_ATTEMPTS_LIMIT = 5


# Function to load credentials from CSV
def load_users():
    users = {}
    try:
        with open(CSV_FILE, mode="r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if "email" in row and "password" in row and "security_question" in row:
                    users[row["email"].strip().lower()] = {
                        "password": row["password"],
                        "security_question": row["security_question"],
                    }
                else:
                    print("Warning: Missing keys in row:", row)
    except FileNotFoundError:
        print(f"{CSV_FILE} not found. A new file will be created upon registration.")
    return users


# Function to save a new user password in CSV
def save_user(email, hashed_password, security_question):
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        if file.tell() == 0:  # If the file is empty, write the header first
            writer.writerow(["email", "password", "security_question"])
        writer.writerow([email, hashed_password.decode('utf-8'), security_question])
        print(f"User {email} registered successfully.")  # Confirmation message


# Function to hash a password
def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


# Function to validate password
def validate_password(password):
    if (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r'[!@#\$%\^&\*\(\)_\+\-=\[\]\{\};:\'",<>\./?\\|`~]', password)
    ):
        return True
    else:
        print(
            "Password must be at least 8 characters long, contain uppercase, lowercase, digits, and special characters."
        )
        return False


# Function to validate email
def validate_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)


# Function to register a new user
def register_user():
    email = input("Enter your email for registration: ").strip()
    if not validate_email(email):
        print("Invalid email format. Please try again.")
        return

    password = input("Enter your password: ").strip()
    if not validate_password(password):
        return

    security_question = input(
        "Enter your security question (for password recovery): "
    ).strip()

    hashed_password = hash_password(password)

    # Save the new user data to the CSV file
    save_user(email, hashed_password, security_question)


# Login function with input validation and password check
def login(users):
    attempts = 0
    while attempts < LOGIN_ATTEMPTS_LIMIT:
        email = input("Enter your email: ").strip()  # Ensure to strip whitespace
        print(f"Checking email: {email}")  # Debugging line

        if not validate_email(email):
            print("Invalid email format.")
            continue

        if email not in users:
            print("Email not registered.")
            continue

        password = input("Enter your password: ").strip()
        if bcrypt.checkpw(
            password.encode("utf-8"), users[email]["password"].encode("utf-8")
        ):
            print("Login successful!")
            return email
        else:
            attempts += 1
            print(
                f"Incorrect password. {LOGIN_ATTEMPTS_LIMIT - attempts} attempts remaining."
            )

    print("Too many failed attempts. Exiting...")
    exit()


# Forgot password functionality
def forgot_password(users):
    email = input("Enter your registered email: ").strip()
    if email in users:
        question = input(f"Security question: {users[email]['security_question']}: ")
        if question == users[email]["security_question"]:
            new_password = input("Enter a new password: ").strip()
            if validate_password(new_password):
                users[email]["password"] = hash_password(new_password)
                print("Password reset successful.")
                # Optionally, save the updated password back to the CSV
                update_user_password(email, users[email]["password"])
        else:
            print("Incorrect answer.")
    else:
        print("Email not registered.")


# Function to update user password in CSV
def update_user_password(email, new_hashed_password):
    users = load_users()
    users[email]["password"] = new_hashed_password.decode('utf-8')

    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["email", "password", "security_question"])  # Write header
        for user_email, user_data in users.items():
            writer.writerow([user_email, user_data["password"], user_data["security_question"]])
    print(f"Password for {email} updated successfully.")


# Function to fetch air quality data using API
def fetch_air_quality(city):
    API_KEY = "8bf49ab05be5f41b4ad2c45e684e33f0"  # Replace with your actual API key
    url = (
        f"http://api.openweathermap.org/data/2.5/air_pollution?appid={API_KEY}&q={city}"
    )
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        aqi = data["list"][0]["main"]["aqi"]
        pollutants = data["list"][0]["components"]
        print(f"AQI for {city}: {aqi}")
        print("Pollutants:")
        print(f"PM2.5: {pollutants['pm2_5']}")
        print(f"PM10: {pollutants['pm10']}")
        print(f"Ozone (O3): {pollutants['o3']}")

        if aqi == 1:
            print("Air quality is good.")
        elif aqi == 2:
            print("Air quality is fair.")
        elif aqi == 3:
            print("Air quality is moderate.")
        elif aqi == 4:
            print("Air quality is poor.")
        elif aqi == 5:
            print("Air quality is very poor.")
    else:
        print("Failed to fetch data.")


# Main program
def main():
    users = load_users()  # Load users from CSV
    print("Welcome to Air Quality Monitoring System!")

    choice = input("Do you want to login (1), register (2), or forgot password (3)? ")
    if choice == '1':
        email = login(users)
        if email:
            city = input("Enter city to check AQI: ")
            fetch_air_quality(city)
    elif choice == '2':
        register_user()
        users = load_users()  # Reload users after registration
    elif choice == '3':
        forgot_password(users)


if __name__ == "__main__":
    main()