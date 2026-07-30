(function () {
    if (typeof vis === 'undefined' || !window.__GRAPH_DATA) return;

    var data = window.__GRAPH_DATA;
    var container = document.getElementById('subdomain-graph');
    if (!container) return;

    var nodes = new vis.DataSet(data.nodes.map(function (n) {
        n.label = n.label || n.id;
        return n;
    }));

    var edges = new vis.DataSet(data.edges);

    var options = {
        autoResize: true,
        height: '100%',
        width: '100%',
        background: '#0a0e0a',
        nodes: {
            borderWidth: 2,
            size: 25,
            font: { color: '#cccccc', size: 12, face: 'monospace' },
            scaling: {
                label: { enabled: true, min: 10, max: 20 }
            }
        },
        edges: {
            smooth: {
                type: 'curvedCW',
                roundness: 0.15
            },
            arrows: { to: { enabled: false } },
            font: {
                color: '#888888',
                size: 10,
                face: 'monospace',
                strokeWidth: 0
            }
        },
        physics: {
            enabled: true,
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                gravitationalConstant: -60,
                centralGravity: 0.008,
                springLength: 150,
                springConstant: 0.04,
                damping: 0.5,
                avoidOverlap: 0.5
            },
            stabilization: {
                iterations: 150,
                updateInterval: 25
            }
        },
        interaction: {
            hover: true,
            tooltipDelay: 100,
            navigationButtons: true,
            keyboard: true
        },
        layout: {
            improvedLayout: true
        },
        groups: {
            domain: {
                shape: 'box',
                borderWidth: 3,
                font: { size: 18, color: '#00ff88' }
            },
            subdomain: {
                shape: 'dot',
                size: 18,
                font: { size: 11, color: '#88ddff' }
            },
            ip: {
                shape: 'ellipse',
                size: 15,
                font: { size: 10, color: '#ffaa44' }
            },
            mx: {
                shape: 'diamond',
                size: 22,
                font: { size: 11, color: '#ff6666' }
            },
            ns: {
                shape: 'triangle',
                size: 22,
                font: { size: 11, color: '#dd88ff' }
            }
        }
    };

    var network = new vis.Network(container, { nodes: nodes, edges: edges }, options);

    network.on('stabilizationProgress', function (params) {
        container.style.opacity = Math.min(1, params.iterations / params.total * 0.8 + 0.2);
    });

    network.once('stabilizationIterationsDone', function () {
        container.style.opacity = 1;
        network.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } });
    });

    window.addEventListener('resize', function () {
        network.fit({ animation: { duration: 200 } });
    });
})();
