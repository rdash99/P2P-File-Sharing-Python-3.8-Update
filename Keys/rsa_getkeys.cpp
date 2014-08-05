#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>
using namespace std;
class RSA{

	
	public:
		mpz_t p,q,n,e,fin,d;
	RSA(int key_size, int min_key_size){
		mpz_init(p);
		mpz_init(q);
		mpz_init(n);
		mpz_init(e);
		mpz_init(fin);
		mpz_init(d);
		gmp_randstate_t st;
		gmp_randinit_default(st);
  		 gmp_randseed_ui(st,2411234);
	//	printf("here\n");
		
  		mpz_urandomb(p,st,key_size);
 	 	mpz_urandomb(q,st,key_size);
		//gmp_printf("p=%Zd\n q=%Zd",p,q);
 	 	mpz_nextprime(p,p);
  		mpz_nextprime(q,q);
	//	gmp_printf("p=%Zd   q=%Zd    ",p,q);
  		mpz_mul(n, p, q);
  		mpz_sub_ui(p, p, 1UL);
  		mpz_sub_ui(q, q, 1UL);
  		mpz_mul(fin, p, q);
		//mpz_mul(fin, p, q);
   
	   	mpz_t num,gcd;
		mpz_init(num);
		mpz_init(gcd);

		mpz_urandomb(e,st,min_key_size);//choose 'e' to be atleast 300-bits initially...
		
		//mpz_set_ui(e,3);
		mpz_set_ui(num,1);
		while(1)
		{
			mpz_gcd(gcd,e,fin);
			if(mpz_cmp(gcd,num)==0)
				break;
			else 
				mpz_add_ui(e,e,1);
		}
			
	    mpz_invert(d, e, fin);
	}
   

	};
///*
	int main(int argc, char* argv[]){
		
		if(argc<3)
		{
			printf("Key size and Min Key size not provided!\n");
			exit(1);
		}
		RSA b(atoi(argv[1]), atoi(argv[2]));
		gmp_printf("%Zd %Zd %Zd",b.e, b.d, b.n);
//		cout<<b.e<<" "<<b.d<<endl;
	}
//*/
