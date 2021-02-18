// A C++ program to print topological 
// sorting of a graph using indegrees. 
#include "kahn.hpp"
#include <vector>
#include <queue>
#include <iostream>

Graph::Graph(int V) 
    : m_V{V}
{ 
    m_adjacents.resize(m_V);
} 

void Graph::addEdge(int u, int v) 
{ 
    // find the uth vector and push in v
	m_adjacents[u].push_back(v); 
} 

// The function to do Topological Sort. 
std::vector<int> Graph::topologicalSort() 
{ 
	// Create a vector to store indegrees of all 
	// vertices. Initialize all indegrees as 0. 
    std::vector<uint32_t> in_degree(m_V, 0); 

	// Traverse adjacency lists to fill indegrees of 
	// vertices. This step takes O(V+E) time 
	for (int u = 0; u < m_V; u++) 
    {
		for (auto itr = m_adjacents[u].cbegin(); itr != m_adjacents[u].cend(); itr++)
        {
			in_degree[*itr]++; 
        }
	} 

	// Create an queue and enqueue 
	// all vertices with indegree 0 
    std::queue<int> q; 
	for (int i = 0; i < m_V; ++i)
    {
		if (in_degree[i] == 0)
        {
			q.push(i); 
        }
    }

	// Initialize count of visited vertices 
	int cnt = 0; 

	// Create a vector to store result (A topological 
	// ordering of the vertices) 
    std::vector<int> top_order; 

	// One by one dequeue vertices from queue and enqueue 
	// adjacents if indegree of adjacent becomes 0 
	while (!q.empty()) { 
		// Extract front of queue (or perform dequeue) 
		// and add it to topological order 
		int u = q.front(); 
		q.pop(); 
		top_order.push_back(u); 

		// Iterate through all its neighbouring nodes 
		// of dequeued node u and decrease their in-degree 
		// by 1 
		for (auto itr = m_adjacents[u].begin(); itr != m_adjacents[u].end(); ++itr)
        {

			// If in-degree becomes zero, add it to queue 
			if (--in_degree[*itr] == 0) 
            {
				q.push(*itr); 
            }
        }

		cnt++; 
	} 

    return top_order;
} 
