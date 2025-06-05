// Convert case status and event summary data into arrays for Chart.js
// Helper function to convert data from JSON into arrays for Chart.js
function getChartData(data, labelField, valueField) {
  var labels = [];
  var values = [];
  data.forEach(function(item) {
    labels.push(item[labelField]);
    values.push(item[valueField]);
  });
  return { labels: labels, values: values };
}

document.addEventListener('DOMContentLoaded', function() {
  // Case Status Chart
  var caseStatusData = getChartData({{ case_status|tojson }}, 'status', 'total');
  var ctx1 = document.getElementById('caseStatusChart').getContext('2d');
  new Chart(ctx1, {
    type: 'pie',
    data: {
      labels: caseStatusData.labels,
      datasets: [{
        data: caseStatusData.values,
        backgroundColor: ['#4caf50', '#ff9800', '#f44336', '#03a9f4']
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Case Status Distribution'
        },
        legend: {
          position: 'bottom'
        }
      }
    }
  });

  // Event Log Summary Chart
  var eventData = getChartData({{ event_summary|tojson }}, 'event_type', 'total');
  var ctx2 = document.getElementById('eventLogChart').getContext('2d');
  new Chart(ctx2, {
    type: 'pie',
    data: {
      labels: eventData.labels,
      datasets: [{
        data: eventData.values,
        backgroundColor: ['#9c27b0', '#e91e63', '#3f51b5', '#009688', '#ff5722']
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Overall Event Log Summary'
        },
        legend: {
          position: 'bottom'
        }
      }
    }
  });
});
