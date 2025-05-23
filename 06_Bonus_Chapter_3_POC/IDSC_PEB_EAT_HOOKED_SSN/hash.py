import sys

# Hash function
def myHash(data):
    hash = 0x99  # initial hash value
    for i in range(0, len(data)):  # for each character in the string
        hash += ord(data[i]) + (hash << 1)  # calculate hash
    print(hash)  # print the computed hash
    return hash  # return the hash

# Main function to test the hash function
if __name__ == "__main__":
    myHash(sys.argv[1])  # compute the hash for the command-line argument
