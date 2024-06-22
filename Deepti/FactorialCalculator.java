package Deepti;

import java.util.Scanner;

public class FactorialCalculator {
	public static long factorialIterative(int n) {
		if(n<0) {
			 throw new IllegalArgumentException("Number must be non-negative.");
		}
		long result = 1;
		for(int i=1; i<=n; i++) {
			result *= i;
		}
		return result;
	}
	// Method to calculate factorial recursively
    public static long factorialRecursive(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("Number must be non-negative.");
        }
        if (n == 0) {
            return 1;
        } else {
            return n * factorialRecursive(n - 1);
        }
    }
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter a non-negative integer:1 ");
        
        if (scanner.hasNextInt()) {
            int number = scanner.nextInt();
            if (number < 0) {
                System.out.println("Error: Number must be non-negative.");
            } else {
                System.out.println("Factorial (Iterative): " + factorialIterative(2));
                System.out.println("Factorial (Recursive): " + factorialRecursive(2));
            }
        } else {
            System.out.println("Error: Please enter a valid integer.");
        }
        
        scanner.close();
    }
}
