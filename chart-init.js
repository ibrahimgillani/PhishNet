// Chart Initialization
let threatChartInstance = null;

function initThreatChart() {
  // Check if Chart library is loaded
  if (typeof Chart === 'undefined') {
    console.error('Chart.js not loaded yet');
    setTimeout(initThreatChart, 100);
    return;
  }
  
  const ctx = document.getElementById('threatChart');
  if (!ctx || threatChartInstance) return;
  
  try {
    threatChartInstance = new Chart(ctx, {
      type: 'line',
      data: {
        labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7'],
        datasets: [{
          label: 'Malicious Links',
          data: [0, 0, 0, 0, 0, 0, 0],
          borderColor: '#FF4D4D',
          backgroundColor: 'rgba(255, 77, 77, 0.1)',
          borderWidth: 3,
          pointRadius: 5,
          pointHoverRadius: 7,
          pointBackgroundColor: '#FF4D4D',
          pointBorderColor: '#FFFFFF',
          pointBorderWidth: 2,
          tension: 0.4,
          fill: true
        }, {
          label: 'Suspicious Links',
          data: [0, 0, 0, 0, 0, 0, 0],
          borderColor: '#FFC107',
          backgroundColor: 'rgba(255, 193, 7, 0.1)',
          borderWidth: 3,
          pointRadius: 5,
          pointHoverRadius: 7,
          pointBackgroundColor: '#FFC107',
          pointBorderColor: '#FFFFFF',
          pointBorderWidth: 2,
          tension: 0.4,
          fill: true
        }, {
          label: 'Safe Links',
          data: [0, 0, 0, 0, 0, 0, 0],
          borderColor: '#00FF88',
          backgroundColor: 'rgba(0, 255, 136, 0.1)',
          borderWidth: 3,
          pointRadius: 5,
          pointHoverRadius: 7,
          pointBackgroundColor: '#00FF88',
          pointBorderColor: '#FFFFFF',
          pointBorderWidth: 2,
          tension: 0.4,
          fill: true
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
          duration: 750
        },
        interaction: {
          mode: 'index',
          intersect: false
        },
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            enabled: true,
            backgroundColor: 'rgba(0, 0, 0, 0.85)',
            titleColor: '#FFFFFF',
            bodyColor: '#FFFFFF',
            borderColor: '#666666',
            borderWidth: 1,
            padding: 10,
            displayColors: true,
            callbacks: {
              label: function(context) {
                return context.dataset.label + ': ' + context.parsed.y + ' clicks';
              }
            }
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            min: 0,
            suggestedMax: 10,
            ticks: {
              color: '#999999',
              stepSize: 1,
              font: { size: 10 }
            },
            grid: {
              color: 'rgba(255, 255, 255, 0.08)',
              drawBorder: true,
              borderColor: 'rgba(255, 255, 255, 0.1)'
            }
          },
          x: {
            ticks: {
              color: '#999999',
              font: { size: 10 }
            },
            grid: {
              color: 'rgba(255, 255, 255, 0.04)',
              drawBorder: true,
              borderColor: 'rgba(255, 255, 255, 0.1)'
            }
          }
        }
      }
    });
    
    // Expose chart instance globally for dashboard-data.js to update
    window.threatChartInstance = threatChartInstance;
    console.log('Chart initialized successfully');
  } catch(e) {
    console.error('Chart initialization error:', e);
  }
}

// Wait for DOM and Chart.js to be ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function() {
    setTimeout(initThreatChart, 200);
  });
} else {
  setTimeout(initThreatChart, 200);
}
