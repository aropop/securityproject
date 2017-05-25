package be.project.middleware;

class Counter {
	int c;
	public Counter() {
		this.c = 0;
	}
	
	public void plus() {
		this.c++;
	}
	
	public int val() {
		return this.c;
	}
}