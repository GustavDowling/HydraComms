import time
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import base64

#We also need to handle the options and such in a more logical way (some options library?)

def generate_keys(private_key_name, public_key_name):
	length = 1024 #1024 bits
	
	#privkey is the file, private_key is the RSA object
	f = open(private_key_name, "w")
	private_key = RSA.generate(length, Random.new().read)
	f.write(private_key.exportKey())
	f.close()
	
	f = open(public_key_name, "w")
	public_key = private_key.publickey()
	f.write(public_key.exportKey())
	f.close()

def generate_signature(private_key, text):
	signature = private_key.sign(text, "") #the empty quote is library specific and irrelevant
	return signature

def get_field_from_id(id_no, field, full_text):
	index_of_item = full_text.find("#id=" + str(id_no))
	if index_of_item == -1: #no such id exists
		return ""
	#this is a search starting from the index of the item, there will be a field in this item.
	index_of_field = full_text.find("#" + field, index_of_item) + len(field) + 2 #the search returns index at #, add 2 for the # and equal sign + length of the field
	
	#get everything before the next hashtag
	field = ""
	currchar = full_text[index_of_field]
	i=1
	while currchar != "#":
		field = field + currchar
		currchar = full_text[index_of_field + i]
		i = i + 1
	
	return field

def get_current_time():
	t = time.localtime()
	return time.strftime("%H:%M:%S", t)

def get_keys(full_text):
	# Returns a list of public keys in the order they appear in the text
	i = 1
	key = "temp"
	keylist = []
	while key != "":
		key = get_field_from_id(i, "key", full_text)
		if key != "none" and key != "":
			keylist.append(key)
		i = i + 1
	return keylist
	
def get_sigs(full_text):
	# Returns a list of lists [sig, username + text] in the order that they appear in the full_text
	sig = "none"
	sigs = []
	i = 1
	while sig != "":
		sig = get_field_from_id(i, "sig", full_text)
		text = get_field_from_id(i, "text", full_text)
		username = get_field_from_id(i, "username", full_text)
		if sig != "none":
			sigs.append([sig, username + text])
		i = i + 1
	return sigs

def verify(new_text, trusted_text):
	#TODO: all dates must be in correct order
	
	#id's in correct order
	id_no = 1
	no_of_ids = new_text.count("#id=")
	
	lastindex = 0
	index = 0
	while True:
		index = new_text.find("#id=" + str(id_no))
		
		if index == -1:
			if id_no > no_of_ids:
				break
			if id_no <= no_of_ids:
				print("ID's are not in correct order")
				return False
				
		elif index < lastindex:
			print("ID's are not in correct order")
			return False
		
		id_no = id_no + 1
		lastindex = index
		
	#all previous text must be unaltered 
	for i in range(len(trusted_text)):
		if new_text[i] != trusted_text[i]:
			print("Previous text has been altered")
			return False
	
	#all signatures must match keys of username
	keys = get_keys(new_text)
	sigs = get_sigs(new_text)
	
	for i in range(len(keys)):
		currentKey = RSA.importKey(keys[i])
		sigobj = (long(sigs[i][0]), "")

		if not currentKey.verify(sigs[i][1], sigobj):
			print("all keys aren't matched with the signatures")
			return False
	
	return True

def m_welcome():
	return raw_input("""Welcome to HydraComms \n
Specify the filename (if it's in this folder, else specify path) 
of the forum you wish to participate in:""")

def m_verify(filename): #verify menu item function
	filename_old = raw_input("Specify the filename of a previous version you know is correct\n(leaving blank will still check authenticity of signatures and id's):\n\n")
	
	try:
		f = open(filename, "r")
	except:
		print(filename + " is not a file yet!")
		return 0
	text = f.read()
	f.close()
	
	if filename_old == "":
		text_old = ""
	else:
		f = open(filename_old, "r")
		text_old = f.read()
		f.close()
	
	verified = verify(text, text_old)
	if verified:
		print("File is authentic")
	else:
		print("File is not authentic")

def get_topics(full_text):
	# Returns a list of all distinct topics
	topics = []
	i = 1
	topic = get_field_from_id(i, "topic", full_text)
	topics.append(topic)
	while topic != "":
		i = i + 1
		topic = get_field_from_id(i, "topic", full_text)
		if topic not in topics:
			topics.append(topic)
	return topics

def m_read(filename):
	# get the topics and create a menu for all the different topics
	# print out all the OP and all the replies along with who said what when
	
	f = open(filename)
	full_text = f.read()
	f.close()
	
	#create the menu
	topics = get_topics(full_text)
	menu_text = ""
	for i in range(len(topics)):
		menu_text = menu_text + str(i+1) + ". " + str(topics[i]) + "\n"
	selected = int(raw_input(menu_text)) - 1
	topic = topics[selected]
	
	#get the id's related to the selected topic
	ids = []
	i = 1
	while True:
		if get_field_from_id(i, "topic", full_text) == topic:
			ids.append(i)
		elif get_field_from_id(i, "topic", full_text) == "":
			break
		i = i + 1
	
	#display the messages
	display_text = "TOPIC: " + topic + "\n\n"
	for id_no in ids:
		display_text = display_text + "Name: " + get_field_from_id(id_no, "username", full_text) \
			 + "      Date: " + get_field_from_id(id_no, "date", full_text) + "\n" \
			 + "Message: " + get_field_from_id(id_no, "text", full_text) + "\n\n"
	
	print(display_text)

def m_write(filename):
	topic = raw_input("Topic: ")
	message = raw_input("Text: ")
	if raw_input("Do you wish to associate a name with this? (y/n): ") == "y":
		private_key_name = raw_input("filename/path of private key: ")
		f = open(private_key_name)
		private_key = RSA.importKey(f.read())
		f.close()
		public_key = private_key.publickey()
		key = public_key.exportKey()
		username = raw_input("What name do you want to use? (must either be unused or associated with correct key) \n")
		b_auth = True
	else:
		sigstr = "none"
		key = "none"
		username = "Anonymous"
		b_auth = False
	
	
	try:
		f = open(filename)
		full_text = f.read()
		f.close()
	except:
		f = open(filename, "w+") #this creates the file if it doesn't exist already
		full_text = ""
		f.close()

	#get the last id number + 1
	id_no = 1
	id_no_string = get_field_from_id(id_no, "id", full_text)
	while id_no_string != "":
		id_no = id_no + 1
		id_no_string = get_field_from_id(id_no, "id", full_text)
		
	#get current time
	current_time = get_current_time()
	
	#digital signature
	if b_auth:
		sigobj = private_key.sign(username + message, "")
		sigstr = str(sigobj[0])
	
	#Add the reply to the end of the file
	text = "#id=" + str(id_no) + "#topic=" + topic + "#date=" + current_time + "#username=" + username + "#sig=" + sigstr + "#key=" + key + "#text=" + message + "#"
	f = open(filename, "a+")
	f.write(text)
	f.close()
	

def menu():
	item = "4"
	while item != "0":
		if item == "4": # specify filename
			filename = m_welcome()
			item = "7"
			
		elif item == "7": #main menu TODO: item 3
			item = raw_input("""What do you want to do?
1. Read
2. Write
3. Verify authenticity
4. Switch working file
5. Quit
6. Generate Private key\n""")
		elif item == "5":
			print("Thank you for using HydraComms")
			item = "0" #quit
		elif item == "3":
			m_verify(filename)
			item = "7"
		elif item == "1":
			m_read(filename)
			item = "7"
		elif item == "6":
			private_key_name = raw_input("Private key name: ")
			public_key_name = raw_input("Public key name: ")
			generate_keys(private_key_name, public_key_name)
			print("Keyfiles " + private_key_name + " and " + public_key_name + " generated in current folder")
			item = "7"
		elif item == "2":
			m_write(filename)
			item = "7"
		else:
			item = "7"
		

def main(args):
	
	menu()
	
	return 0

if __name__ == '__main__':
	import sys
	sys.exit(main(sys.argv))
