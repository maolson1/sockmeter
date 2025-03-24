# This script was used to generate stats_test_data.h.

import numpy

shape_param = 1.5
numvals = 5000
percentile_90 = 1000
scale = percentile_90 / (-numpy.log(0.1))**(1/shape_param)

weibull_data = numpy.random.weibull(shape_param, numvals) * scale
x = numpy.linspace(0, numpy.max(weibull_data), 1000)

def print_in_columns(iterable, num_columns, printer):
    column = 0
    for item in iterable:
        printer(item)
        column += 1
        if column == num_columns:
            print("")
            column = 0

tested_percentiles = range(1, 100)

print("ULONG tested_percentiles[] = {")
print_in_columns(iter(tested_percentiles), 30, lambda i: print("{},".format(i), end=""))
print("};")

print("ULONG64 percentiles[] = {")
print_in_columns(iter(tested_percentiles), 30, lambda i: print("{},".format(int(numpy.percentile(weibull_data, i))), end=""))
print("};")

print("ULONG64 test_data[] = {")
print_in_columns(iter(weibull_data), 40, lambda i: print("{},".format(int(i)), end=""))
print("};")

# import matplotlib.pyplot
# matplotlib.pyplot.hist(weibull_data, bins=30, density=True, alpha=0.6, color='b', label='Histogram')
# matplotlib.pyplot.show()
