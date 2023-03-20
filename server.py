import pickle

DB_FILE='server.db'

class Server():

    def __init__(self):
        try:
            with open(DB_FILE,'rb') as file:
                self.key_bundles=pickle.load(file).key_bundles
        except FileNotFoundError:
            self.key_bundles={}
            with open(DB_FILE,'wb') as file:
                pickle.dump(self,file)


    def post(self,username:str,key_bundle:object):
        self.key_bundles[username]=key_bundle
        with open(DB_FILE,'wb') as file:
            pickle.dump(self,file)

    def get_key_bundle(self,username:str):
        if username in self.key_bundles:
            return self.key_bundles[username]
        else:
            return None

