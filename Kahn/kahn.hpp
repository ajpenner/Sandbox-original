// A C++ program to print topological 
// sorting of a graph using indegrees. 
#include <list> 
#include <utility>
#include <vector>

// Class to represent a graph 
class Graph { 
	// No. of vertices' 
	int m_V; 

	// Pointer to an array containing adjacency lists
    std::vector<std::pair<int, std::vector<int>>> m_adjacents; 

    // independant nodes
    std::vector<int> m_terminal;

public: 

	Graph(int V); 

	// Function to add an edge to graph 
	void addEdge(int u, int v);

    void addTerminal(int u);

	// prints a Topological Sort of the complete graph 
    std::vector<int> topologicalSort(); 
}; 
