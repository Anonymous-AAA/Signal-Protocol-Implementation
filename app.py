import client as c


# initialize the user
username=input("Enter username\n")
user=c.User(username)

#publish keys
user.publish()


while True:

    option=input("1.Send Message\n2.Receive Message\n")

    match option:

        case "1":
            receiver=input("Enter the receiver of the message\n")
            if not receiver in  user.key_bundles:
                user.initialHandshake(receiver)
                user.generateSendSecretKey(receiver)
                user.sendInitialMessage(receiver,f"Initial message from {username}")
            
            #message=input("Enter the message to be send\n")
            #user.sendInitialMessage(receiver,message)
        
        case "2":
            message=user.recvInitialMessage()
        
        case default:
            break


