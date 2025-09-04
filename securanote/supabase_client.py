from supabase import create_client

# Replace with your Supabase project URL and key
SUPABASE_URL = "https://vebmigukwzzptqdgdqtf.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZlYm1pZ3Vrd3p6cHRxZGdkcXRmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY4OTc2NDAsImV4cCI6MjA3MjQ3MzY0MH0.OUtAJ9wRThIAP3sCI157jhGd7MlTS2zqSsZvknT9I7M"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
