import random 
import string 

def generate_ssn():
    return f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"

def generate_account():
    return ''.join(random.choices(string.digits, k=12))

def generate_phone():
    return f"({random.randint(100, 999)})-{random.randint(100, 999)}-{random.randint(1000, 9999)}"

names = [
    "Alice Johnson", "Bob Smith", "Charlie Davis", "Diana Evans" 
    "Edward Wilson", "Fiona Brown", "George Clark", "Hannah Lewis", "Ian Walker", "Julia Hall"]
domains = ["gmail.com", "yahoo.com", "outlook.com", "company.com"]   
cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix"]

print("-- Generating customer data")
for i in range (1,2401):
    name = random.choices(names)+str(i)
    email = name.lower ().replace(" ", ".") + "@" + random.choice(domains)
    ssn = generate_ssn()
    account = generate_account()
    balance = round(random.uniform(100, 100000), 2)
    phone = generate_phone()
    address = f"{random.randint(1,9999)} Main St, {random.choice(cities)}, ST {random.randint(10000,99999)}"

    print(f"INSERT INTO customers (name, email, account_number, balance, ssn, phone, address) VALUES ('{name}', '{email}', '{account}', {balance}, '{ssn}', '{phone}', '{address}');")