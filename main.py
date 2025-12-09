# main.py
"""
main.py
Main application integrating all utility functions.
"""

from utils import (
    capitalize_words,
    is_valid_email,
    read_json,
    write_json,
    get_timestamp,
    add_numbers,
    percentage,
    get_request,
    log
)

def main():
    # ----------------------------
    # STRING UTIL TEST
    # ----------------------------
    print("--- STRING TEST ---")
    text = "hello world from ram"
    print("Capitalized:", capitalize_words(text))

    # ----------------------------
    # EMAIL VALIDATION
    # ----------------------------
    print("\n--- EMAIL VALIDATION ---")
    email = "ram@example.com"
    print(email, "valid?", is_valid_email(email))

    # ----------------------------
    # JSON FILE OPERATIONS
    # ----------------------------
    sample_data = {
        "name": "Ram",
        "role": "DevOps Engineer",
        "timestamp": get_timestamp()
    }

    write_json("data.json", sample_data)
    print("Written JSON:", sample_data)

    read_data = read_json("data.json")
    print("Read JSON:", read_data)

    # ----------------------------
    # MATH UTILITIES
    # ----------------------------
    print("\n--- MATH TEST ---")
    print("Sum:", add_numbers(10, 25))
    print("Percentage:", percentage(40, 50), "%")

    # ----------------------------
    # API REQUEST
    # ----------------------------
    print("\n--- API REQUEST ---")
    url = "https://jsonplaceholder.typicode.com/posts/1"
    response = get_request(url)
    print("API response:", response)

    # ----------------------------
    # LOGGING
    # ----------------------------
    print("\n--- LOGGING ---")
    log("Main program executed successfully.")
    print("Log entry added.")

if __name__ == "__main__":
    main()

