import abc

T_FUNC_STR = 't_func_'

class BackEnd(abc.ABC):
    
    def __init__(self,*args):
        pass
    @abc.abstractmethod
    def table(self,tablename):
        pass

    def get_tables_list(self):
        tabs = []
        for i in self.__dir__():
            if i.startswith(T_FUNC_STR):
                tabs.append(i)
        return tabs
    
    def _run_t_func(self,name: str,*args):
        fname = T_FUNC_STR + name
        if hasattr(self,fname):
            return self.__getattribute__(fname)(*args)
        return None

class BackEndError(Exception):
    """
    Exception error class for PortScanner class

    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'BackEndError exception {0}'.format(self.value)

        



