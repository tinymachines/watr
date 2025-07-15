#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "watr/protocol.h"

namespace py = pybind11;

PYBIND11_MODULE(watr_core, m) {
    m.doc() = "WATR custom protocol package";
    
    py::class_<watr::Protocol>(m, "Protocol")
        .def(py::init<>())
        .def("craft_packet", &watr::Protocol::craft_packet,
             "Craft a packet with the given data")
        .def("parse_packet", &watr::Protocol::parse_packet,
             "Parse a packet from bytes")
        .def("set_header_field", &watr::Protocol::set_header_field,
             "Set a header field value")
        .def("get_header_field", &watr::Protocol::get_header_field,
             "Get a header field value");
}