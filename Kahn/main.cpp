#include "kahn.hpp"
#include <iostream>

// Driver program to test included functions 
int main() 
{ 
	// Create a graph 
	Graph g(6); 
	g.addEdge(5, 2); 
	g.addEdge(5, 0); 
	g.addEdge(4, 0); 
	g.addEdge(4, 1); 
	g.addEdge(2, 3); 
	g.addEdge(3, 1); 

    std::cout << "Following is a Topological Sort of\n"; 
	auto top_order = g.topologicalSort(); 

    std::cout << "Size is: " << top_order.size() << std::endl;
	// Print topological order 
	for (int i = 0; i < top_order.size(); i++) 
		std::cout << top_order[i] << " "; 
    std::cout << std::endl; 



	// Create a graph 
	Graph g2(6); 
	g2.addEdge(22, 75); 
	g2.addEdge(22, 11); 
	g2.addEdge(2,  11); 
	g2.addEdge(2,   6); 
	g2.addEdge(75, 33); 
	g2.addEdge(33,  6); 

    std::cout << "Following is a Topological Sort of\n"; 
	auto top_order2 = g2.topologicalSort(); 

    std::cout << "Size is: " << top_order2.size() << std::endl;
	// Print topological order 
	for (int i = 0; i < top_order2.size(); i++) 
		std::cout << top_order2[i] << " "; 
    std::cout << std::endl; 





	return 0; 
} 

