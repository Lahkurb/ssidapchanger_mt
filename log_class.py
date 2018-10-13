import datetime

class Log():
    
    def __init__(self, file_debug, file_error):
        self.log_debug = open(file_debug, 'a')
        self.log_error = open(file_error, 'a')
        #print('file opened')
        self.buf = ''
            
    def __del__(self):
        log_debug = self.__init__
        log_error = self.__init__
        self.log_debug.close
        self.log_error.close
        #print('file closed')

    def debug(self, content):
        log_debug = self.__init__
        self.time_now = datetime.datetime.now().strftime("%H:%M:%S")
        self.content = content
        buf = self.time_now + ' : ' + self.content + '\n'
        print(buf)
        self.log_debug.write(buf)
        #self.log_debug.close
    
    def error_log(self, address, content):
        log_error = self.__init__
        self.time_now = datetime.datetime.now().strftime("%H:%M:%S")
        self.address = address
        self.content = content
        buf = self.time_now + ' : ' + address  + self.content + '\n'
        print(buf)
        self.log_error.write(buf)
        #file = file + '_' + cfg[config]['ERROR_FILE']

