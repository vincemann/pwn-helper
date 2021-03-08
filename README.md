# pwn-helper
### what is it  
helper lib for pwntools  
  
### installation  
```python3 -m pip install dist/pwnhelper-0.1.0-py3-none-any.whl```  
test with ``` python3 -c 'import pwnhelper'```   
this should not throw an error
  
### example usage  
```python 
from pwnhelper.debugger import *  
binary = "/opt/phoenix/i486/format-four"  
dbg = Debugger(binary)  
```  
see [this](https://github.com/vincemann/exploit-education_phoenix-solutions/blob/main/pwntools/format4.py) example script  
