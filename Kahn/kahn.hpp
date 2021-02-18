// A C++ program to print topological 
// sorting of a graph using indegrees. 
#include <list> 
#include <vector>

// Class to represent a graph 
class Graph { 
	// No. of vertices' 
	int m_V; 

	// Pointer to an array containing adjacency lists
    std::vector<std::vector<int>> m_adjacents; 

public: 

	Graph(int V); 

	// Function to add an edge to graph 
	void addEdge(int u, int v); 

	// prints a Topological Sort of the complete graph 
    std::vector<int> topologicalSort(); 
}; 
