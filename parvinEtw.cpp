#include <iostream>
#include "krabs.hpp"
#include "src/utils/JsonUtils.hpp"
#include "src/etw/EtwConsumer.hpp"
#include "src/etw/Filter.hpp"

using namespace std;

int main(int argc, char const *argv[])
{
    krabs::user_trace trace(L"spara_edr");
    EtwConsumer consumer(L"Microsoft-Windows-Kernel-Process", (ULONGLONG) 0x10 | 0x40);
    trace.enable(consumer.provider);
    trace.start();
    /*
    Filter.cpp -> parses json to filter
    {
        name: string
        predicate: 
            bool operator
    }
    Detection.cpp -> inject detection filters to providers
        responses -> kill, show alert
    Processor.cpp -> 
    */

    krabs::provider<> provider(L"Microsoft-Windows-Kernel-Process");
    provider.any(0xFFFF);
    provider.trace_flags(EVENT_ENABLE_PROPERTY_PROCESS_START_KEY | EVENT_ENABLE_PROPERTY_TS_ID | EVENT_ENABLE_PROPERTY_SID);
    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        cout << "Test" << endl;
        krabs::schema schema(record, trace_context.schema_locator);
        int event_id = schema.event_id();
        //LOG(INFO) << L"Event " << event_id << " opcode:" << schema.event_opcode() << " ver:" << schema.event_version();
        if (true) {
            ULONG64 ProcessStartKey = 0;
            for (int i = 0; i < record.ExtendedDataCount; i++) {
                EVENT_HEADER_EXTENDED_DATA_ITEM item = record.ExtendedData[i];
                if (item.ExtType == EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY) {
                    auto key = reinterpret_cast<PEVENT_EXTENDED_ITEM_PROCESS_START_KEY>(item.DataPtr);
                    ProcessStartKey = key->ProcessStartKey;
                }
            }
            krabs::parser parser(schema);
            
            if (ProcessStartKey) {
                //LOG(INFO) << L"startkey: " << ProcessStartKey;
                FILETIME createTime;
                if (parser.try_parse<FILETIME>(L"CreateTime", createTime)) {

                    UINT64 time = static_cast<__int64>(createTime.dwHighDateTime) << 32 | createTime.dwLowDateTime;
                    UINT64 time2 = static_cast<UINT64>(time / 10000000) - 11644473600;

                    BYTE uuid[16] = { 196, 217, 31, 103 };
                    memcpy(uuid + 4, &time2, sizeof(UINT64));
                    memcpy(uuid + 8, &ProcessStartKey, sizeof(ProcessStartKey));
                    char str[37] = {};
                    sprintf_s(str,
                        "%s-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        "671fd9c4", uuid[5], uuid[4], uuid[7], uuid[6],
                        uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
                    );
                    printf("process guid: %s\n", str);
                }
            }
            json obj;
            std::wstring value_wstring;
            std::string value_string;
            int guid_len;
            INT8 number_8;
            INT16 number_16;
            INT32 number_32;
            INT64 number_64;
            UINT8 u_number_8;
            UINT16 u_number_16;
            UINT32 u_number_32;
            UINT64 u_number_64;
            FILETIME value_filetime;
            float value_float;
            double value_double;
            bool value_bool;
            GUID value_guid;
            wchar_t guid_string[64] = { 0 };
            std::wstring wstring_value;
            krabs::sid sid_value;
            for (auto prop : parser.properties()) {
                std::wstring name = prop.name();
                std::string name_str = json_utils::to_utf8(name);

                _TDH_IN_TYPE type = prop.type();

                switch (type)
                {
                case TDH_INTYPE_NULL:
                    break;
                case TDH_INTYPE_UNICODESTRING:
                    value_wstring = parser.parse<std::wstring>(name);
                    obj[name_str] = json_utils::to_utf8(value_wstring);
                    break;
                case TDH_INTYPE_ANSISTRING:
                    value_string = parser.parse<std::string>(name);
                    obj[name_str] = value_string;
                    break;
                case TDH_INTYPE_INT8:
                    number_8 = parser.parse<INT8>(name);
                    obj[name_str] = number_8;
                    break;
                case TDH_INTYPE_INT16:
                    number_16 = parser.parse<INT16>(name);
                    obj[name_str] = number_16;
                    break;
                case TDH_INTYPE_INT32:
                    number_32 = parser.parse<INT32>(name);
                    obj[name_str] = number_32;
                    break;
                case TDH_INTYPE_INT64:
                    number_64 = parser.parse<INT64>(name);
                    obj[name_str] = number_64;
                    break;

                case TDH_INTYPE_UINT8:
                    u_number_8 = parser.parse<UINT8>(name);
                    obj[name_str] = u_number_8;
                    break;
                case TDH_INTYPE_UINT16:
                    u_number_16 = parser.parse<UINT16>(name);
                    obj[name_str] = u_number_16;
                    break;
                case TDH_INTYPE_UINT32:
                    u_number_32 = parser.parse<UINT32>(name);
                    obj[name_str] = u_number_32;
                    break;
                case TDH_INTYPE_UINT64:
                    u_number_64 = parser.parse<UINT64>(name);
                    obj[name_str] = u_number_64;
                    break;
                case TDH_INTYPE_FLOAT:
                    value_float = parser.parse<float>(name);
                    obj[name_str] = value_float;
                    break;
                case TDH_INTYPE_DOUBLE:
                    value_double = parser.parse<float>(name);
                    obj[name_str] = value_double;
                    break;
                case TDH_INTYPE_BOOLEAN:
                    value_bool = parser.parse<bool>(name);
                    obj[name_str] = value_bool;
                    break;
                case TDH_INTYPE_BINARY:
                    break;
                case TDH_INTYPE_GUID:
                    value_guid = parser.parse<GUID>(name);
                    guid_len = StringFromGUID2(value_guid, guid_string, 64);
                    if (guid_len) {
                        wstring_value = std::wstring(guid_string);
                        obj[name_str] = json_utils::to_utf8(wstring_value);
                    }
                    break;
                case TDH_INTYPE_POINTER:
                    break;
                case TDH_INTYPE_FILETIME:
                    value_filetime = parser.parse<FILETIME>(name);
                    obj[name_str] = static_cast<__int64>(value_filetime.dwHighDateTime) << 32 | value_filetime.dwLowDateTime;
                    break;
                case TDH_INTYPE_SYSTEMTIME:
                    break;
                case TDH_INTYPE_SID:
                    sid_value = parser.parse<krabs::sid>(name);
                    obj[name_str] = sid_value.sid_string;
                    break;
                case TDH_INTYPE_HEXINT32:
                    break;
                case TDH_INTYPE_HEXINT64:
                    break;
                case TDH_INTYPE_MANIFEST_COUNTEDSTRING:
                    break;
                case TDH_INTYPE_MANIFEST_COUNTEDANSISTRING:
                    break;
                case TDH_INTYPE_RESERVED24:
                    break;
                case TDH_INTYPE_MANIFEST_COUNTEDBINARY:
                    break;
                case TDH_INTYPE_COUNTEDSTRING:
                    break;
                case TDH_INTYPE_COUNTEDANSISTRING:
                    break;
                case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
                    break;
                case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
                    break;
                case TDH_INTYPE_NONNULLTERMINATEDSTRING:
                    break;
                case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
                    break;
                case TDH_INTYPE_UNICODECHAR:
                    break;
                case TDH_INTYPE_ANSICHAR:
                    break;
                case TDH_INTYPE_SIZET:
                    break;
                case TDH_INTYPE_HEXDUMP:
                    break;
                case TDH_INTYPE_WBEMSID:
                    break;
                default:
                    break;
                }

            }
            //obj["event_id"] = event_id;
            cout << obj.dump() << endl;
            //LOG(INFO) << obj.dump();

        }
        });
    return 0;
}

    