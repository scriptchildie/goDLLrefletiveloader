# Reflectively load a DLL in pure GO
The code is a ported version of:
https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection
https://blog.malicious.group/writing-your-own-rdi-srdi-loader-using-c-and-asm/#tl-dr

The code will:
- Read the bytes from disk
- Allocate a memory RW region in memory
- Copy the dll sections to the allocated memory and change .text region to RX
- Apply the necessary relocations
- Resolve function addresses and patch the IAT (currently only by the function name)
- Run the entry point code (it will only execute if our code runs from DllMain, DLL_PROCESS_ATTACH)

Future features:
- Resolve function addresses by ordinal
- Create a slice of exported functions and their addresses

  Blog post: https://www.scriptchildie.com/code-injection-techniques/5.-reflective-dll-injection
