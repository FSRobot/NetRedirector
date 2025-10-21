#define Q_PROPERTY_CREATE_Q_H(TYPE, NAME)                         \
private:                                                          \
    TYPE m_##NAME{};                                              \
public:                                                           \
    Q_PROPERTY(TYPE NAME READ get##NAME WRITE set##NAME NOTIFY NAME##Changed) \
    TYPE get##NAME() const { return m_##NAME; }                  \
    void set##NAME(TYPE value) {                                  \
        if (m_##NAME != value) { m_##NAME = value; emit NAME##Changed(); } \
    }                                                             \
Q_SIGNALS:                                                        \
    void NAME##Changed();
