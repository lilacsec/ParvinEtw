#pragma once
#include <string>
#include "krabs.hpp"

namespace ParvinEtw
{
    namespace Predicates
    {
        struct BasePredicate
        {
            const std::string name;
            BasePredicate(std::string name) : name(name) {};
            virtual bool operator()(const EVENT_RECORD &, const krabs::trace_context &) const = 0;
        };

        struct AnyEvent : BasePredicate {
            AnyEvent(std::string name) : BasePredicate(name) {};

            bool operator()(const EVENT_RECORD &, const krabs::trace_context &) const
            {
                return true;
            }
        };

        class PredicateMerger {
            public:
            void addPredicate(BasePredicate& pred);

            bool filter(const EVENT_RECORD &record, const krabs::trace_context &context)
            {
                return true;
            }
        }
    }
}