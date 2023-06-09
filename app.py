import client as c


# initialize the user
username=input("Enter username\n")
user=c.User(username)

#publish keys
user.publish()


while True:

    option=input("1.Send Message\n2.Receive Messages\nPress enter to exit\n")

    match option:

        case "1":
            receiver=input("Enter the receiver of the message\n")

            while receiver==username:
                receiver=input("Cannot send message to self.\nEnter the receiver of the message\n")


            if not receiver in  user.key_bundles:
                if not user.initialHandshake(receiver) :
                    continue
                user.generateSendSecretKey(receiver)
                message=input("Enter the message to be send\n")
                user.sendInitialMessage(receiver,message)
            else: 
                message=input("Enter the message to be send\n")
                user.sendMessage(receiver,message)
        
        case "2":
            message=user.recvAllMessages() #if not initial message it will call recvMessage()
            if message:
                print(message)
        
        case default:
            break


