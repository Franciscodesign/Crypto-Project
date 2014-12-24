package Test;

import java.math.BigInteger;

import PrimeNumber.GenPrime;
import PrimeNumber.ProbablePrime;;

/**
 * TestPrime.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class TestPrime {
	public static void main(String[] args) {

		//BigInteger n = new BigInteger("32416190071");
		/*
		 * 5577033906663259073644233807875967924644763019211901716047021194635354477431576257412282801225365635186512941754200111629827624190496906193901054443071634971039372799071325837136194212324633795851520009754984439180984658327143731952495254420727550535894815479779197363725193757633038383358730139914969148920272427869274523804412018486215709494984629657222144170772766814071391985769035687051027600495909407460077199610151962982289960836587750406046445007956459614304245173831220108580986741029185374481175361953851213369921813331344877776509447570958224395007503520564989794566224726276693274584447984808502055620008864259189459588241733635011687184141996335494992333546264000541919997279719938694577547975616904288996053432234780866557432198893516976521095104088757338163882171215624346719550444991468657916980531689085950032930865109099052946432617717860301539083161505989393884250229464040864708007166572962882588968342903
		 * 203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249 917319836219304274280243803104015000563790123
		 * 
		 */
		long start = System.currentTimeMillis();  
		//BigInteger n = new GenPrime().genBigPrime();
		BigInteger n = new BigInteger(args[0]);
		test4(n,64); // do chinh xac 1/4^64 = 1/2^128
		long elapsedTime = System.currentTimeMillis() - start;
		System.out.println(" DONE. Time run: " + (elapsedTime/1000)
				+ "(s)");
		
		// generation prime
		// System.out.println(new GenPrime().genBigPrime(3072));
		System.out.println(new GenPrime().genPrime(3072));
	}
	
	// isProbablePrime (BigInteger class)
	public static void test2(BigInteger n, int certainty){ 
		System.out.println(n.toString()
				+ " \nis "
				+ (n.isProbablePrime(certainty) ? "probably prime"
						: "composite"));
	}
		
	// Big Integer
	public static void test4(BigInteger n, int certainty){	 

		System.out.println(n.toString()
				+ " \nis "
				+ (ProbablePrime.millerRabin(n,certainty) ? "probably prime"
						: "composite"));
	}
}
