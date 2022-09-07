#include <string>
#include <iostream>
#include "krabs.hpp"
#include "Filter.hpp"

class EtwConsumer {
public:
    krabs::provider<> provider;
private:
    std::wstring providerName;
public:
    EtwConsumer(std::wstring providerName, ULONGLONG any): provider(providerName) {
        this->providerName = providerName;
        provider.any(any);
        provider.trace_flags(EVENT_ENABLE_PROPERTY_PROCESS_START_KEY | EVENT_ENABLE_PROPERTY_TS_ID | EVENT_ENABLE_PROPERTY_SID);
        this->provider = provider;
        krabs::event_filter filterLogs(krabs::predicates::any_event);
        krabs::event_filter filterDetection(krabs::predicates::any_event);
        filterLogs.add_on_event_callback([&](const EVENT_RECORD &record, const krabs::trace_context &trace_context) {
            ParvinEtw::Predicates::AnyEvent base("test");
            if (base.operator()(record, trace_context)) {
                std::cout << "FILTER: " << base.name << std::endl;
            }
        });
        filterDetection.add_on_event_callback([&](const EVENT_RECORD &record, const krabs::trace_context &trace_context) {
            ParvinEtw::Predicates::AnyEvent base("testdete4ction");
            if (base.operator()(record, trace_context)) {
                std::cout << "detection: " << base.name << std::endl;
            }
        });
        provider.add_filter(filterLogs);
        provider.add_filter(filterDetection);
        provider.add_on_event_callback([&](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
            this->Callback(record, trace_context);
        });
    };

    // add process guid
    void Callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        int event_id = schema.event_id();
        std::cout << "id: " << event_id << std::endl;
    };
};
