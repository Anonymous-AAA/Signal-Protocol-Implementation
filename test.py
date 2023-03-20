import client as c

bob=c.User('Bob')
bob.publish()
print(c.server.get('Bob'))
print(c.server.get('Bo'))
