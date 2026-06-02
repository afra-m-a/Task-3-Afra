import sys
from gui import PhishingTriageApp  

def main():
    try:
        app = PhishingTriageApp()
        app.mainloop()
    except KeyboardInterrupt:
        print("Application terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()