cert_check: cert_check.o general.o extensions.o GeneralName.o PEM_decode.o
	gcc -o cert_check cert_check.o general.o extensions.o GeneralName.o PEM_decode.o

cert_check.o: cert_check.c cert_check.h
	gcc -c cert_check.c -o cert_check.o

general.o: general.c cert_check.h
	gcc -c general.c -o general.o

extensions.o: extensions.c cert_check.h
	gcc -c extensions.c -o extensions.o

GeneralName.o: GeneralName.c cert_check.h
	gcc -c GeneralName.c -o GeneralName.o

PEM_decode.o: PEM_decode.c cert_check.h
	gcc -c PEM_decode.c -o PEM_decode.o
