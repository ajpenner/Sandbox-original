#include "kahn.hpp"
#include <iostream>

// Driver program to test included functions 
int main() 
{ 
	// Create a graph given in the 
	// above diagram 
	Graph g(6); 
	g.addEdge(5, 2); 
	g.addEdge(5, 0); 
	g.addEdge(4, 0); 
	g.addEdge(4, 1); 
	g.addEdge(2, 3); 
	g.addEdge(3, 1); 

    std::cout << "Following is a Topological Sort of\n"; 
	auto top_order = g.topologicalSort(); 

	// Print topological order 
	for (int i = 0; i < top_order.size(); i++) 
		std::cout << top_order[i] << " "; 
    std::cout << std::endl; 
	return 0; 
} 

