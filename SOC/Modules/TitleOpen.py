import random

def titleOpen():
    var = random.randint(1,2)
    if var == 1:
        print('''                                           
 @@@@@@    @@@@@@    @@@@@@    
@@@@@@@   @@@@@@@@  @@@@@@@@    
!@@       @@!  @@@  @@!  @@@    
!@!       !@!  @!@  !@!  
!!@@!!    @!@  !@!  @!@    
 !!@!!!   !@!  !!!  !@!    
     !:!  !!:  !!!  !!:     
    !:!   :!:  !:!  :!:     
:::: ::   ::::: ::  :::::::      
:: : :     : :  :    : : :         
 
                           ''')
    if var == 2:
        print('''

   _____                     
  / ____|                   
 | (___   ___   ___  
  \___ \ / _ \ / _ |
  ____) | (_) | (_
 |_____/ \___/ \___/
                          
                         
                         
                    
''')
    print("\n The SOC Analyst's all-in-one tool to "
          "automate and speed up workflow ")
    input('\n Press Enter to continue..')
