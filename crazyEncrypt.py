def crazyEncrypt(plaintext):
    ciphertext = ""
    key = 5
    for character in plaintext:
        # Ignore all non alphabetic characters
        if (not character.islower() and not character.isupper()):
            ciphertext += character
            continue # do not change key
        
        if (character.islower()):
            base = ord('a')
            currChar = ord(character)

            tmpChar = ((currChar-base) + key) % 26
            tmpChar = chr(tmpChar + base)
            ciphertext += tmpChar

        elif (character.isupper()):
            base = ord('A')
            currChar = ord(character)

            tmpChar = ((currChar-base) + key) % 26
            tmpChar = chr(tmpChar + base)
            ciphertext += tmpChar


        if (key == 0):
            key = 5
        else:
            key -= 1

    return ciphertext
def crazyDecrypt(ciphertext):
    plaintext = ""
    key = 5
    for character in ciphertext:
        # Ignore all non alphabetic characters
        if (not character.islower() and not character.isupper()):
            plaintext += character
            continue # do not change key
        
        if (character.islower()):
            base = ord('a')
            currChar = ord(character)

            tmpChar = ((currChar-base) - key + 26) % 26
            tmpChar = chr(tmpChar + base)
            plaintext += tmpChar

        elif (character.isupper()):
            base = ord('A')
            currChar = ord(character)

            tmpChar = ((currChar-base) - key + 26) % 26
            tmpChar = chr(tmpChar + base)
            plaintext += tmpChar

        if (key == 0):
            key = 5
        else:
            key -= 1

    return plaintext

print (crazyEncrypt("This is the credentials pinkFoxOnStereoids:hunter2"))
print (crazyDecrypt(crazyEncrypt("This is the credentials pinkFoxOnStereoids:hunter2")))