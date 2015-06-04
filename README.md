# s(4)u for Windows #

sU is a demonstration program using the S4U extension in msv1_.0.

It allows the creation of a cmd.exe with the context of any user without requiring the password.

## Usage ##

Create a cmd.exe with a local user security context:


    s4u.exe .\user


Create a cmd.exe with a domain user security context:

    s4u.exe DOMAIN\user

Create a cmd.exe with and add specific SID:

    s4u.exe .\user S-1-5-18