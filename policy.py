import random

# Function to generate a random IPv4 address
def generate_ip():
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))

# Generate 50 TCP rules
for i in range(1, 51):
    # Generate random IP addresses and dstif value
    action = 'drop'
    src_ip = generate_ip()
    dst_ip = generate_ip()
    dst_if = random.randint(0,4)
    # Choose random ipproto value
    ipproto = 'tcp'
    # Construct and print the rule
    rule = f"rule:{i} action={action} srcip4={src_ip} dstif={dst_if} dstip4={dst_ip} ipproto={ipproto}"
    print(rule)

for i in range(51, 101):
    # Generate random IP addresses and dstif value
    action = 'drop'
    src_ip = generate_ip()
    dst_ip = generate_ip()
    dst_if = random.randint(0,4)
    # Choose random ipproto value
    ipproto = 'udp'
    # Construct and print the rule
    rule = f"rule:{i} action={action} srcip4={src_ip} dstif={dst_if} dstip4={dst_ip} ipproto={ipproto}"
    print(rule)