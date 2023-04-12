import pickle

DB_FILE='server.db'

class Server():

    def __init__(self):
        try:
            self.refresh()
        except FileNotFoundError:
            self.key_bundles={}
            self.messages={}
            self.dump()


    def dump(self):
        with open(DB_FILE,'wb') as file:
            pickle.dump(self,file)
    
    def refresh(self):
        with open(DB_FILE,'rb') as file:
            pkl=pickle.load(file)
            self.key_bundles=pkl.key_bundles
            self.messages=pkl.messages



    def publish(self,username:str,key_bundle:object):
        self.refresh()
        self.key_bundles[username]=key_bundle
        self.dump()

    def get_key_bundle(self,username:str) -> dict | None:
        self.refresh()
        if username in self.key_bundles:
            bundle=self.key_bundles[username].copy()

            if len(bundle['OPK_p'])>0 :
                bundle['OPK_p']=self.key_bundles[username]['OPK_p'].pop()
                self.dump()
            else :
                bundle['OPK_p']=b'\xff'*32     #No OPK is indicated by this
            return bundle   #dont pass reference
        else:
            return None


    def send(self,fr:str,to:str,message:bytes):
        self.refresh()
        self.messages[(fr,to)]=message
        self.dump()


    def get_message(self,username:str) -> tuple[str,bytes]:

        self.refresh()
        out=('none',bytes())

        for x,y in self.messages.items():
            if x[1]==username:
                out=x[0],y
                break
        return out

        


