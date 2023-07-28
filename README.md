# 7111 cut 1

Exploit cwpk

This is based on safe scanning pdf. http://www.security-explorations.com/

Thanks for this amazing job!, but I'm still on mine this friend from security-explorations, it's a Payserver

Okay, let's go ...

The first box must have the uart port active (TX / RX).

Sometimes the (turnips) of the engineers make mistakes, (luckily for the Payservers)

After entering the Box, check whether it is vulnerable or not.

Type the cmd.

peek fe00d05c

If it gives a hex value of 0x01100110 (continue), if the value 0x00000000 appears, no (continue) you will crash into a wall, sorry, this is not for you.

The final key is at address fe24c150.

enter please

display fe24c150 4

Lucky, you can play in the euromillions that you'll hit the nape

Ps: soon I'll put the code for Visual Studio net c# here 

#############################################################################

add new script(Ferro_fixo)

I tested on friend and box(Pace maxtv ), key out OK
