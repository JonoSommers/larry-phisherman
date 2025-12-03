from detector import score_email

def main():
    result = score_email("test@example.com", "Hi", "Just testing")
    print(result)

if __name__ == "__main__":
    main()
