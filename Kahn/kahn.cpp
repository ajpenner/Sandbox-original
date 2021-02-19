// A C++ program to print topological 
// sorting of a graph using indegrees. 
#include "kahn.hpp"
#include <vector>
#include <queue>
#include <algorithm>
#include <set>
#include <cstdint>
#include <cassert>

Graph::Graph(int V) 
    : m_V{V}
{ 
} 

void Graph::addTerminal(int u)
{
    m_terminal.push_back(u);
}
/*
void Graph::addEdges(const std::vector<std::pair<int, int>>& idList)
{
    for(const auto& valuePair : idList)
    {
        addEdge(valuePair.first, valuePair.second);
    }
}
*/
void Graph::addEdge(int u, int v)
{
    // find the uth vector and push in v
    auto it = std::find_if(m_adjacents.begin(), m_adjacents.end(),
            [u](const auto& value)
            {
              return (u == value.first);
            });
    if(it != m_adjacents.end())
    {
        it->second.push_back(v);
    }
    else
    {
        m_adjacents.push_back(std::make_pair(u, std::vector<int>{v}));
    }
}

void injectData(std::vector<std::pair<int, uint32_t>>& in_degree, int id)
{
    auto degreeIt = std::find_if(in_degree.begin(), in_degree.end(), 
        [id](const auto& valuePair)
        {
            return (id == valuePair.first);
        });
        if(degreeIt == in_degree.end())
        {
            in_degree.push_back(std::make_pair(id, 0));
        }
}

// The function to do Topological Sort. 
std::vector<int> Graph::topologicalSort() 
{ 
	// Create a vector to store indegrees of all vertices. Initialize all indegrees as 0. 
    std::vector<std::pair<int, uint32_t>> in_degree; 

	// Traverse adjacency lists to fill indegrees of vertices. 
	for (const auto& adjacent : m_adjacents) 
    {
        const auto& id = adjacent.first;
        injectData(in_degree, id); // if the id is not in the in_degree list, add it with a zero entry
        for (const auto& value : adjacent.second)
        {
            auto degreeIt = std::find_if(in_degree.begin(), in_degree.end(), 
                    [value](const auto& valuePair)
                    {
                        return (value == valuePair.first);
                    });
            if(degreeIt != in_degree.end())
            {
                degreeIt->second++;
            }
            else
            {
                in_degree.push_back(std::make_pair(value, 1)); // if we are pushing back, we have one
            }
        }
	} 

    assert(in_degree.size() == m_V);

	// Create an queue and enqueue all vertices with indegree 0 
    std::queue<int> q;
	for (int i = 0; i < m_V; ++i)
    {
		if (in_degree.at(i).second == 0)
        {
			q.push(in_degree.at(i).first); 
        }
    }

	// Create a vector to store result (A topological 
	// ordering of the vertices) 
    std::vector<int> top_order; 

	// One by one dequeue vertices from queue and enqueue 
	// adjacents if indegree of adjacent becomes 0 
	while (!q.empty()) { 
		// Extract front of queue (or perform dequeue) 
		// and add it to topological order 
		int id = q.front(); 
		q.pop(); 
		top_order.push_back(id); 
        auto adjacentIt = std::find_if(m_adjacents.cbegin(), m_adjacents.cend(), 
                [id](const auto& valuePair)
                {
                    return (id == valuePair.first);
                });

        if(adjacentIt == m_adjacents.cend())
        {
            // No edge connecting u to another node is specified
            continue;
        }

		// Iterate through all its neighbouring nodes of dequeued node id 
        // and decrease their in-degree by 1 
		for (const auto& value : adjacentIt->second)
        {
            auto degree = std::find_if(in_degree.begin(), in_degree.end(),
                    [value](const auto& valuePair)
                    {
                        return (value == valuePair.first);
                    });

			// If in-degree becomes zero, add it to queue 
			if (--degree->second == 0) 
            {
				q.push(value); 
            }
        }
	} 

    return top_order;
}
