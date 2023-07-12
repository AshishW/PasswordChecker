import requests 
import hashlib # for sha1 hashing
import sys

def requests_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the api again')
	return res


def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

def pwned_api_check(password):
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = requests_api_data(first5_char)
	return get_password_leaks_count(response, tail)

def main(args):
	for password in args: # to check for multiple passwords in arguments
		count = pwned_api_check(password.strip())
		if count:
			print(f"{password} was found {count} times... You should probably change your password")
		else:
			print(f"{password} was not found! Carry on!")
	return 'done!'

def get_passwords_list():
	password_file = open("passwords.txt", "r")
	password_list = password_file.readlines()
	password_file.close()
	return password_list

if __name__ == '__main__':
	# sys.exit(main(sys.argv[1:])) 
	sys.exit(main(get_passwords_list())) 

# sys.exit() is used to make sure we exit and move back to commandline


# whenever trying to code things always go step by step and check if each step is working as intended. Try testing with input whose output you already know and check if you are getting the same result as it should give in the output.
# for eg: here we first created the request_api_data function then the 
# pwned_api_check function and then others step by step by trying and testing at each step of creating the function, figuring the things that weren't working as intended by doing research online.
# this helps us to break down the problem into small parts that can be solved more easily than trying to find the solution to the whole problem at once.
# when you get error, try thinking and figuring out what went wrong, check each steps properly.
# this is something you become better and better as you code more.
